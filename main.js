const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const readline = require('readline');
const https = require('https');
const os = require('os');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const gradientColors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function gradientText(text) {
  const colors = [gradientColors.cyan, gradientColors.green, gradientColors.yellow, gradientColors.magenta];
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += colors[i % colors.length] + text[i];
  }
  return result + gradientColors.reset;
}

function printBanner() {
  console.log(gradientText('\n┌─┐┌─┐┌─┐┌─┐┬  ┌─┐          '));
  console.log(gradientText('│ ┬│ ││ ││ ┬│  ├┤           '));
  console.log(gradientText('└─┘└─┘└─┘└─┘┴─┘└─┘          '));
  console.log(gradientText('┌─┐─┐ ┬┌┬┐┌─┐┌┐┌┌─┐┬┌─┐┌┐┌  '));
  console.log(gradientText('├┤ ┌┴┬┘ │ ├┤ │││└─┐││ ││││  '));
  console.log(gradientText('└─┘┴ └─ ┴ └─┘┘└┘└─┘┴└─┘┘└┘  '));
  console.log(gradientText('┌─┐┌┐┌┌┬┐┬┬  ┬┬┬─┐┬ ┬┌─┐    '));
  console.log(gradientText('├─┤│││ │ │└┐┌┘│├┬┘│ │└─┐    '));
  console.log(gradientText('┴ ┴┘└┘ ┴ ┴ └┘ ┴┴└─└─┘└─┘    \n'));
  console.log(gradientColors.cyan + '========================================' + gradientColors.reset);
  console.log(gradientColors.green + '    Chrome Extension Security Scanner' + gradientColors.reset);
  console.log(gradientColors.cyan + '========================================\n' + gradientColors.reset);
}

function getExtensionPaths() {
  const paths = [];
  const platform = os.platform();

  if (platform === 'win32') {
    paths.push(path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default', 'Extensions'));
    paths.push(path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Profile 1', 'Extensions'));
  } else if (platform === 'darwin') {
    paths.push(path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions'));
    paths.push(path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome', 'Profile 1', 'Extensions'));
  } else if (platform === 'linux') {
    paths.push(path.join(os.homedir(), '.config', 'google-chrome', 'Default', 'Extensions'));
    paths.push(path.join(os.homedir(), '.config', 'google-chrome', 'Profile 1', 'Extensions'));
  }

  return paths;
}

async function findExtensions() {
  const extensions = [];
  const extPaths = getExtensionPaths();

  for (const extPath of extPaths) {
    try {
      const dirs = await fs.readdir(extPath);
      for (const dir of dirs) {
        const versionPath = path.join(extPath, dir);
        const versions = await fs.readdir(versionPath);
        const latestVersion = versions.sort().reverse()[0];
        const manifestPath = path.join(versionPath, latestVersion, 'manifest.json');

        try {
          const manifestContent = await fs.readFile(manifestPath, 'utf8');
          const manifest = JSON.parse(manifestContent);
          extensions.push({
            id: dir,
            name: manifest.name || 'Unknown',
            version: latestVersion,
            path: path.join(versionPath, latestVersion),
            manifest: manifest
          });
        } catch (err) {
          continue;
        }
      }
    } catch (err) {
      continue;
    }
  }

  return extensions;
}

function animateLoading(message) {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let i = 0;

  const interval = setInterval(() => {
    process.stdout.write('\r' + gradientColors.yellow + frames[i] + ' ' + message + gradientColors.reset);
    i = (i + 1) % frames.length;
  }, 100);

  return interval;
}

async function checkVirusTotal(extensionId) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'www.virustotal.com',
      path: `/api/v3/files/${extensionId}`,
      method: 'GET'
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({ detected: false, score: 'N/A', error: 'API key required' });
      });
    });

    req.on('error', () => {
      resolve({ detected: false, score: 'N/A', error: 'Cannot check VirusTotal' });
    });

    req.setTimeout(3000, () => {
      req.destroy();
      resolve({ detected: false, score: 'N/A', error: 'Timeout' });
    });

    req.end();
  });
}

function analyzeConnections(manifest) {
  const connections = {
    hosts: [],
    permissions: [],
    urls: [],
    external: []
  };

  if (manifest.permissions) {
    connections.permissions = manifest.permissions.filter(p =>
      p.includes('://') || p.includes('*')
    );

    manifest.permissions.forEach(perm => {
      if (perm.includes('://')) {
        const match = perm.match(/https?:\/\/([^\/]+)/);
        if (match) connections.hosts.push(match[1]);
      }
    });
  }

  if (manifest.content_scripts) {
    manifest.content_scripts.forEach(script => {
      if (script.matches) {
        script.matches.forEach(match => {
          connections.urls.push(match);
          const hostMatch = match.match(/https?:\/\/([^\/]+)/);
          if (hostMatch) connections.hosts.push(hostMatch[1]);
        });
      }
    });
  }

  if (manifest.web_accessible_resources) {
    connections.external.push('Web accessible resources defined');
  }

  if (manifest.externally_connectable) {
    if (manifest.externally_connectable.matches) {
      connections.external.push(...manifest.externally_connectable.matches);
    }
    if (manifest.externally_connectable.ids) {
      connections.external.push(...manifest.externally_connectable.ids);
    }
  }

  connections.hosts = [...new Set(connections.hosts)];
  return connections;
}

function analyzeIntegrations(manifest) {
  const integrations = [];

  if (manifest.oauth2) {
    integrations.push(`OAuth2: ${manifest.oauth2.client_id || 'Present'}`);
  }

  if (manifest.key) {
    integrations.push('Extension has public key');
  }

  if (manifest.background) {
    if (manifest.background.persistent !== undefined) {
      integrations.push(`Background: ${manifest.background.persistent ? 'Persistent' : 'Non-persistent'}`);
    }
    if (manifest.background.service_worker) {
      integrations.push('Service Worker background');
    }
  }

  if (manifest.storage) {
    integrations.push(`Storage: ${Object.keys(manifest.storage).join(', ')}`);
  }

  if (manifest.commands) {
    integrations.push(`Commands: ${Object.keys(manifest.commands).length} registered`);
  }

  return integrations;
}

function scanForSuspicious(manifest) {
  const suspicious = [];

  const dangerousPermissions = [
    'management', 'webRequest', 'webRequestBlocking', 'debugger',
    'tabs', 'cookies', 'history', 'bookmarks', 'downloads',
    'proxy', 'storage', 'unlimitedStorage', 'clipboardRead',
    'clipboardWrite', 'nativeMessaging', 'fileSystem'
  ];

  if (manifest.permissions) {
    manifest.permissions.forEach(perm => {
      if (dangerousPermissions.includes(perm)) {
        suspicious.push(`Dangerous permission: ${perm}`);
      }
    });
  }

  if (manifest.content_security_policy) {
    if (manifest.content_security_policy.includes('unsafe-eval') ||
        manifest.content_security_policy.includes('unsafe-inline')) {
      suspicious.push('Unsafe CSP policy detected');
    }
  }

  if (manifest.externally_connectable) {
    suspicious.push('External connections allowed');
  }

  return suspicious;
}

async function scanExtension(extension) {
  console.log(gradientColors.cyan + '\n┌─────────────────────────────────────────┐' + gradientColors.reset);
  console.log(gradientColors.green + `│ Scanning: ${extension.name}` + ' '.repeat(Math.max(0, 38 - extension.name.length)) + gradientColors.reset + gradientColors.cyan + '│' + gradientColors.reset);
  console.log(gradientColors.cyan + '├─────────────────────────────────────────┤' + gradientColors.reset);
  console.log(gradientColors.yellow + `│ ID: ${extension.id}` + ' '.repeat(Math.max(0, 38 - extension.id.length)) + gradientColors.reset + gradientColors.cyan + '│' + gradientColors.reset);
  console.log(gradientColors.yellow + `│ Version: ${extension.version}` + ' '.repeat(Math.max(0, 38 - extension.version.length)) + gradientColors.reset + gradientColors.cyan + '│' + gradientColors.reset);
  console.log(gradientColors.cyan + '└─────────────────────────────────────────┘' + gradientColors.reset);

  let loading = animateLoading('Analyzing connections...');
  await new Promise(resolve => setTimeout(resolve, 1500));

  const connections = analyzeConnections(extension.manifest);
  clearInterval(loading);

  console.log(gradientColors.magenta + '\n📡 NETWORK CONNECTIONS:' + gradientColors.reset);
  if (connections.hosts.length > 0) {
    connections.hosts.forEach(host => {
      console.log(gradientColors.red + `  ⚠️  ${host}` + gradientColors.reset);
    });
  } else {
    console.log(gradientColors.green + '  ✅ No external hosts detected' + gradientColors.reset);
  }

  console.log(gradientColors.magenta + '\n🔗 INTEGRATIONS:' + gradientColors.reset);
  const integrations = analyzeIntegrations(extension.manifest);
  if (integrations.length > 0) {
    integrations.forEach(int => {
      console.log(gradientColors.yellow + `  🔄 ${int}` + gradientColors.reset);
    });
  } else {
    console.log(gradientColors.green + '  ✅ No integrations detected' + gradientColors.reset);
  }

  console.log(gradientColors.magenta + '\n⚠️  SUSPICIOUS ACTIVITIES:' + gradientColors.reset);
  const suspicious = scanForSuspicious(extension.manifest);
  if (suspicious.length > 0) {
    suspicious.forEach(sus => {
      console.log(gradientColors.red + `  🚨 ${sus}` + gradientColors.reset);
    });
  } else {
    console.log(gradientColors.green + '  ✅ No suspicious activities found' + gradientColors.reset);
  }

  console.log(gradientColors.magenta + '\n📋 PERMISSIONS:' + gradientColors.reset);
  if (extension.manifest.permissions && extension.manifest.permissions.length > 0) {
    extension.manifest.permissions.slice(0, 10).forEach(perm => {
      console.log(gradientColors.blue + `  • ${perm}` + gradientColors.reset);
    });
    if (extension.manifest.permissions.length > 10) {
      console.log(gradientColors.blue + `  • ... and ${extension.manifest.permissions.length - 10} more` + gradientColors.reset);
    }
  } else {
    console.log(gradientColors.green + '  ✅ No permissions required' + gradientColors.reset);
  }

  loading = animateLoading('Checking VirusTotal...');
  await new Promise(resolve => setTimeout(resolve, 2000));
  const vtResult = await checkVirusTotal(extension.id);
  clearInterval(loading);

  console.log(gradientColors.magenta + '\n🛡️  VIRUS SCAN:' + gradientColors.reset);
  if (vtResult.error) {
    console.log(gradientColors.yellow + `  ⚠️  ${vtResult.error}` + gradientColors.reset);
  } else {
    console.log(gradientColors.green + `  ✅ Score: ${vtResult.score}/100` + gradientColors.reset);
  }

  console.log(gradientColors.cyan + '\n' + '='.repeat(45) + gradientColors.reset);
}

async function main() {
  printBanner();

  let loading = animateLoading('Loading extensions...');
  const extensions = await findExtensions();
  clearInterval(loading);

  if (extensions.length === 0) {
    console.log(gradientColors.red + '\n❌ No extensions found!' + gradientColors.reset);
    rl.close();
    return;
  }

  console.log(gradientColors.green + `\n📦 Found ${extensions.length} extensions:\n` + gradientColors.reset);

  extensions.forEach((ext, index) => {
    console.log(gradientColors.yellow + `  ${index + 1}. ${ext.name}` + gradientColors.reset);
    console.log(gradientColors.blue + `     ID: ${ext.id}\n` + gradientColors.reset);
  });

  rl.question(gradientColors.cyan + '\n🔍 Select extension number to scan: ' + gradientColors.reset, async (answer) => {
    const choice = parseInt(answer) - 1;

    if (choice >= 0 && choice < extensions.length) {
      await scanExtension(extensions[choice]);
    } else {
      console.log(gradientColors.red + '\n❌ Invalid selection!' + gradientColors.reset);
    }

    rl.close();
  });
}

main().catch(console.error);
