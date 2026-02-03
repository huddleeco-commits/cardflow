module.exports = {
  packagerConfig: {
    name: 'CardFlow Scanner',
    executableName: 'cardflow-scanner',
    // icon: './assets/icon',  // Uncomment when icon.ico is added
    asar: true,
    appBundleId: 'com.cardflow.scanner',
    appCopyright: 'Copyright © 2024 CardFlow',
    win32metadata: {
      CompanyName: 'CardFlow',
      ProductName: 'CardFlow Scanner',
      FileDescription: 'Desktop scanner agent for CardFlow',
      OriginalFilename: 'cardflow-scanner.exe'
    }
  },
  rebuildConfig: {},
  makers: [
    {
      name: '@electron-forge/maker-squirrel',
      config: {
        name: 'CardFlowScanner',
        authors: 'CardFlow',
        description: 'Desktop scanner agent for CardFlow - Upload and identify trading cards',
        // setupIcon: './assets/icon.ico',  // Uncomment when icon.ico is added
        setupExe: 'CardFlow Scanner Setup.exe',
        noMsi: true
      }
    }
  ],
  plugins: [
    {
      name: '@electron-forge/plugin-auto-unpack-natives',
      config: {}
    }
  ]
};
