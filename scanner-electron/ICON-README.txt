CardFlow Scanner - Icon Setup
=============================

To enable the custom icon for the Windows installer:

1. Create a 256x256 PNG icon and save as assets/icon.png

2. Convert to ICO format using one of these methods:
   - Online: https://convertio.co/png-ico/ or https://icoconvert.com/
   - Command line with ImageMagick: convert icon.png -define icon:auto-resize=256,128,64,48,32,16 icon.ico

3. Save the ICO file as: assets/icon.ico

4. Uncomment the icon lines in forge.config.js:
   - packagerConfig.icon
   - makers[0].config.setupIcon

5. Rebuild with: npm run make

The SVG source is available at assets/icon.svg for reference.
