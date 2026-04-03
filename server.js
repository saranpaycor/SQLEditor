const express = require('express');
const multer = require('multer');
const sql = require('mssql');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

// PowerShell script for Windows SSO.
// Supports two modes:
//   - Current identity (Domain/User/Pass empty): plain Integrated Security=SSPI
//   - Explicit credentials (Domain/User/Pass supplied): LogonUser LOGON_NEW_CREDENTIALS
//     impersonation == same as "runas /netonly", uses Kerberos for outbound network auth
const SSO_PS_SCRIPT = `
param([string]$Server, [string]$Database, [string]$SqlFile,
      [string]$WinDomain='', [string]$WinUser='', [string]$WinPass='')
Add-Type -AssemblyName System.Data
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public class WinImpersonate {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string pass,
        int logonType, int logonProvider, out IntPtr token);
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern bool CloseHandle(IntPtr h);
    public static int LastError() { return Marshal.GetLastWin32Error(); }
}
"@
\$useImpersonate = (\$WinUser -ne '' -or \$WinDomain -ne '')
\$token = [IntPtr]::Zero
\$impCtx = \$null
if (\$useImpersonate) {
    # LOGON32_LOGON_NEW_CREDENTIALS=9, LOGON32_PROVIDER_WINNT50=3
    # Creates a token whose credentials are used ONLY for outbound network calls (runas /netonly)
    \$ok = [WinImpersonate]::LogonUser(\$WinUser, \$WinDomain, \$WinPass, 9, 3, [ref]\$token)
    if (-not \$ok) {
        \$err = [WinImpersonate]::LastError()
        @{success=\$false;message="LogonUser failed (Win32 error \$err). Check domain/username/password."} | ConvertTo-Json -Compress
        exit 1
    }
    \$identity = New-Object System.Security.Principal.WindowsIdentity(\$token)
    \$impCtx = \$identity.Impersonate()
}
try {
    \$sqlText = [System.IO.File]::ReadAllText(\$SqlFile)
    \$statements = @([System.Text.RegularExpressions.Regex]::Split(\$sqlText, '(?mi)^\\s*GO\\s*\$') | Where-Object { \$_.Trim() -ne '' })
    \$connStr = "Server=\$Server;Database=\$Database;Integrated Security=SSPI;TrustServerCertificate=true;Connection Timeout=30;"
    \$conn = \$null
    try {
        \$conn = New-Object System.Data.SqlClient.SqlConnection(\$connStr)
        \$conn.Open()
    } catch {
        @{success=\$false;message=\$_.Exception.Message} | ConvertTo-Json -Compress
        exit 1
    }
    \$resList = [System.Collections.ArrayList]@()
    foreach (\$stmt in \$statements) {
        \$trimmed = \$stmt.Trim()
        if ([string]::IsNullOrWhiteSpace(\$trimmed)) { continue }
        try {
            \$cmd = New-Object System.Data.SqlClient.SqlCommand(\$trimmed, \$conn)
            \$cmd.CommandTimeout = 120
            \$reader = \$cmd.ExecuteReader()
            \$hasRS = \$false
            do {
                if (\$reader.FieldCount -gt 0) {
                    \$hasRS = \$true
                    \$cols = [string[]](0..(\$reader.FieldCount-1) | ForEach-Object { \$reader.GetName(\$_) })
                    \$rows = [System.Collections.ArrayList]@()
                    while (\$reader.Read()) {
                        \$row = [ordered]@{}
                        for (\$i=0;\$i -lt \$reader.FieldCount;\$i++) {
                            \$v = \$reader.GetValue(\$i)
                            \$row[\$cols[\$i]] = if (\$v -is [System.DBNull]) { \$null } else { "\$v" }
                        }
                        [void]\$rows.Add(\$row)
                    }
                    [void]\$resList.Add(@{type='resultset';columns=[object[]]\$cols;rows=[object[]]\$rows})
                }
            } while (\$reader.NextResult())
            \$affected = \$reader.RecordsAffected
            \$reader.Close()
            if (-not \$hasRS) {
                \$msg = if (\$affected -ge 0) { "\$affected row(s) affected" } else { 'Command completed successfully.' }
                [void]\$resList.Add(@{type='message';message=\$msg})
            }
        } catch {
            [void]\$resList.Add(@{type='message';message=("Error: " + \$_.Exception.Message)})
        }
    }
    \$conn.Close()
    [PSCustomObject]@{success=\$true;results=[object[]]\$resList} | ConvertTo-Json -Depth 15 -Compress
} finally {
    if (\$impCtx)  { \$impCtx.Undo() }
    if (\$token -ne [IntPtr]::Zero) { [WinImpersonate]::CloseHandle(\$token) | Out-Null }
}
`;

const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(express.json());
app.use(express.static('public'));

// Split SQL into individual statements, skipping GO separators
function splitStatements(sqlText) {
  return sqlText
    .split(/^\s*GO\s*$/im)
    .map(s => s.trim())
    .filter(s => s.length > 0);
}

// Parse "server\instance" or "server,port" or "server:port" notation
function parseServer(raw) {
  let serverHost = raw.trim();
  let instanceName = undefined;
  let port = undefined;

  // Handle "server\instance"
  const backslash = serverHost.indexOf('\\');
  if (backslash !== -1) {
    instanceName = serverHost.slice(backslash + 1);
    serverHost = serverHost.slice(0, backslash);
  }

  // Handle "server,port" or "server:port" (only when no instance)
  if (!instanceName) {
    const commaIdx = serverHost.indexOf(',');
    const colonIdx = serverHost.lastIndexOf(':');
    if (commaIdx !== -1) {
      port = parseInt(serverHost.slice(commaIdx + 1), 10);
      serverHost = serverHost.slice(0, commaIdx);
    } else if (colonIdx !== -1 && !serverHost.startsWith('[')) {
      // avoid stripping IPv6
      port = parseInt(serverHost.slice(colonIdx + 1), 10);
      serverHost = serverHost.slice(0, colonIdx);
    }
  }

  return { serverHost, instanceName, port };
}

// Run SQL via PowerShell with optional LogonUser impersonation
function runSso(server, database, sqlText, winDomain, winUser, winPass) {
  return new Promise((resolve, reject) => {
    const ts = Date.now();
    const sqlPath    = path.join(os.tmpdir(), `sqleditor_sql_${ts}.sql`);
    const scriptPath = path.join(os.tmpdir(), `sqleditor_ps_${ts}.ps1`);
    const cleanup = () => {
      try { fs.unlinkSync(sqlPath); }    catch (_) {}
      try { fs.unlinkSync(scriptPath); } catch (_) {}
    };
    fs.writeFileSync(sqlPath, sqlText, 'utf8');
    fs.writeFileSync(scriptPath, SSO_PS_SCRIPT, 'utf8');

    const args = [
      '-NonInteractive', '-NoProfile',
      '-File', scriptPath,
      '-Server',   server,
      '-Database', database || 'master',
      '-SqlFile',  sqlPath,
    ];
    if (winUser)   { args.push('-WinUser',   winUser); }
    if (winDomain) { args.push('-WinDomain', winDomain); }
    if (winPass)   { args.push('-WinPass',   winPass); }

    const proc = spawn('powershell', args);
    let stdout = '', stderr = '';
    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.stderr.on('data', d => { stderr += d.toString(); });
    proc.on('error', err => { cleanup(); reject(err); });
    proc.on('close', () => {
      cleanup();
      const out = stdout.trim();
      if (!out) return reject(new Error(stderr.trim() || 'PowerShell returned no output.'));
      try { resolve(JSON.parse(out)); }
      catch (e) { reject(new Error(`Cannot parse output: ${out.slice(0, 300)}`)); }
    });
  });
}

// Build mssql config from request body.
// Returns { config, driver } where driver is 'sql' (tedious) or 'sso' (PowerShell).
function buildConfig(body) {
  const { server, database, authType, username, password, domain, port: portOverride } = body;

  const { serverHost, instanceName, port: parsedPort } = parseServer(server);
  const port = portOverride ? parseInt(portOverride, 10) : parsedPort;

  // Windows SSO — handled via PowerShell with optional LogonUser impersonation
  if (authType === 'sso') {
    const instancePart = instanceName ? `\\${instanceName}` : '';
    const portPart     = port ? `,${port}` : '';
    return {
      config: {
        server:    `${serverHost}${instancePart}${portPart}`,
        database:  database || 'master',
        winDomain: domain   || '',
        winUser:   username || '',
        winPass:   password || '',
      },
      driver: 'sso'
    };
  }

  const config = {
    server: serverHost,
    database: database || 'master',
    options: {
      encrypt: false,
      trustServerCertificate: true,
      enableArithAbort: true,
    },
    requestTimeout: 60000,
    connectionTimeout: 30000,
  };

  if (instanceName) config.options.instanceName = instanceName;
  if (port)         config.port = port;

  if (authType === 'windows') {
    config.authentication = {
      type: 'ntlm',
      options: {
        domain: domain || '',
        userName: username,
        password: password,
      },
    };
  } else {
    config.authentication = {
      type: 'default',
      options: {
        userName: username,
        password: password,
      },
    };
  }

  return { config, driver: 'sql' };
}

// POST /api/test-connection
app.post('/api/test-connection', async (req, res) => {
  let pool;
  try {
    const { config, driver } = buildConfig(req.body);
    if (driver === 'sso') {
      const result = await runSso(config.server, config.database, 'SELECT 1 AS connected',
        config.winDomain, config.winUser, config.winPass);
      return res.json(result.success
        ? { success: true, message: 'Connection successful (Windows SSO)' }
        : { success: false, message: result.message });
    }
    pool = await sql.connect(config);
    await pool.close();
    res.json({ success: true, message: 'Connection successful' });
  } catch (err) {
    if (pool) try { await pool.close(); } catch (_) {}
    let msg = err.message;
    if (err.code === 'ENOTFOUND' || msg.includes('ENOTFOUND') || msg.includes('getaddrinfo')) {
      const attempted = (err.message.match(/ENOTFOUND (\S+)/) || [])[1] || req.body.server;
      msg = `DNS lookup failed for "${attempted}".\n\nTip: Use the full FQDN (e.g. pftsql02.perftest.paycor.com) instead of a short hostname, and make sure you are on the correct network / VPN.\n\nAlso ensure you selected "Windows SSO" as the authentication type.`;
    }
    res.status(400).json({ success: false, message: msg });
  }
});

// POST /api/execute  — accepts multipart (file upload) or JSON (filePath)
app.post('/api/execute', upload.single('sqlFile'), async (req, res) => {
  let pool;
  let tempPath = null;

  try {
    let sqlText;

    if (req.file) {
      // File uploaded via multipart form
      tempPath = req.file.path;
      sqlText = fs.readFileSync(tempPath, 'utf8');
    } else if (req.body.filePath) {
      // Local file path provided
      const filePath = req.body.filePath;
      if (!fs.existsSync(filePath)) {
        return res.status(400).json({ success: false, message: `File not found: ${filePath}` });
      }
      sqlText = fs.readFileSync(filePath, 'utf8');
    } else {
      return res.status(400).json({ success: false, message: 'No SQL file provided.' });
    }

    const { config, driver } = buildConfig(req.body);

    // Windows SSO — delegate entirely to PowerShell
    if (driver === 'sso') {
      const result = await runSso(config.server, config.database, sqlText,
        config.winDomain, config.winUser, config.winPass);
      return res.json(result);
    }

    pool = await sql.connect(config);

    const statements = splitStatements(sqlText);
    const allResults = [];

    for (const stmt of statements) {
      const request = pool.request();
      const result = await request.query(stmt);

      if (result.recordsets) {
        for (const rs of result.recordsets) {
          if (rs.length > 0) {
            allResults.push({ columns: Object.keys(rs[0]), rows: rs });
          }
        }
      }

      if (result.rowsAffected && result.rowsAffected.some(n => n > 0)) {
        const total = result.rowsAffected.reduce((a, b) => a + b, 0);
        allResults.push({ message: `${total} row(s) affected` });
      }
    }

    if (allResults.length === 0) {
      allResults.push({ message: 'Query executed successfully. No rows returned.' });
    }

    res.json({ success: true, results: allResults });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  } finally {
    if (pool) try { await pool.close(); } catch (_) {}
    if (tempPath && fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`SQL Editor running at http://localhost:${PORT}`);
});
