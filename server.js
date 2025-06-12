require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

app.post('/scan', async (req, res) => {
  const domain = req.body.domain;
  const results = {};

  if (!domain) {
    return res.status(400).json({ error: "Domain is required" });
  }

  console.log(`🔍 Starting recon for: ${domain}`);

  try {
    // WHOIS
    try {
      const whois = await runCommand(`whois ${domain}`);
      results.whois = whois;
      console.log("✅ WHOIS completed");
    } catch (err) {
      results.whois = `WHOIS failed: ${err}`;
    }

    // DNS Lookup using nslookup (Windows)
    try {
      const dns = await runCommand(`nslookup ${domain}`);
      results.dns = dns;
      console.log("✅ DNS Lookup completed");
    } catch (err) {
      results.dns = `DNS lookup failed: ${err}`;
    }

    // NMAP (Fast scan)
    try {
      const nmap = await runCommand(`nmap -F ${domain}`);
      results.nmap = nmap;
      console.log("✅ Nmap completed");
    } catch (err) {
      results.nmap = `Nmap failed: ${err}`;
    }

    // IP Info Lookup using ip-api.com
    try {
      const nsOutput = await runCommand(`nslookup ${domain}`);
      const ipLine = nsOutput
        .split('\n')
        .find(line => line.includes('Address:') && !line.includes('127.0.0.1'));

      const ipAddress = ipLine ? ipLine.split('Address:')[1].trim() : null;

      if (ipAddress) {
        const ipInfo = await getIPInfo(ipAddress);
        results.network_info = ipInfo;
        console.log("✅ IP info lookup completed using ip-api.com");
      } else {
        results.network_info = 'Could not extract IP address for IP info lookup.';
      }
    } catch (err) {
      results.network_info = `IP lookup failed: ${err}`;
    }

    res.json(results);
  } catch (err) {
    console.error("❌ Server error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Utility function to run terminal commands
function runCommand(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { shell: 'cmd.exe' }, (error, stdout, stderr) => {
      if (error) return reject(stderr || error.message);
      resolve(stdout);
    });
  });
}

// Free IP info lookup using ip-api.com
const http = require('http'); // Add at the top if not already

async function getIPInfo(ip) {
  return new Promise((resolve, reject) => {
    const url = `http://ip-api.com/json/${ip}`; // ✅ use HTTP for free tier

    http.get(url, (res) => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json);
        } catch (e) {
          reject("Failed to parse ip-api.com response");
        }
      });
    }).on('error', (err) => {
      reject(err.message);
    });
  });
}


app.listen(PORT, () => {
  console.log(`🚀 Recon app running on http://localhost:${PORT}`);
});
