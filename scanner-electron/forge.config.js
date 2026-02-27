module.exports = {
  packagerConfig: {
    name: 'SlabTrack Desktop Scanner',
    executableName: 'slabtrack-desktop-scanner',
    icon: './assets/icon',
    asar: true,
    appBundleId: 'com.slabtrack.desktop-scanner',
    appCopyright: 'Copyright © 2025 SlabTrack',
    win32metadata: {
      CompanyName: 'SlabTrack',
      ProductName: 'SlabTrack Desktop Scanner',
      FileDescription: 'Desktop scanner for SlabTrack - Bulk scan trading cards via ADF',
      OriginalFilename: 'slabtrack-desktop-scanner.exe'
    }
  },
  rebuildConfig: {},
  makers: [
    {
      name: '@electron-forge/maker-squirrel',
      config: {
        name: 'SlabTrackDesktopScanner',
        authors: 'SlabTrack',
        description: 'Desktop scanner for SlabTrack - Scan and identify trading cards via duplex ADF',
        setupIcon: './assets/icon.ico',
        setupExe: 'SlabTrack Desktop Scanner Setup.exe',
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
