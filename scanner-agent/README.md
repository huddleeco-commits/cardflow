# CardFlow Scanner Agent

Desktop scanner agent for Ricoh fi-8170 (and other document scanners) integration with CardFlow.

## Features

- Watches a folder for new scanned images
- Automatically pairs front/back images (sequential: odd=front, even=back)
- Real-time upload to CardFlow
- WebSocket connection for live status updates in CardFlow UI

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Edit `config.json`:
   ```json
   {
     "watchFolder": "C:\\Scans",
     "serverUrl": "http://localhost:3000",
     "token": "YOUR_CARDFLOW_TOKEN",
     "pairingMode": "sequential"
   }
   ```

3. Get your token from CardFlow:
   - Go to `/scanner` in CardFlow
   - Copy the token displayed

4. Configure your scanner to save images to the watch folder

5. Start the agent:
   ```bash
   npm start
   ```

## Scanner Setup (Ricoh fi-8170)

1. Set output folder to your `watchFolder` path
2. Use sequential numbering (001, 002, 003...)
3. Scan front first, then back
4. Agent automatically pairs odd (front) with even (back)

## Pairing Modes

- **sequential** (default): Files paired by order - 1st=front, 2nd=back, 3rd=front, etc.
- **suffix**: Files paired by naming - `card_a.jpg`/`card_b.jpg` or `card_front.jpg`/`card_back.jpg`

## Config Options

| Option | Description | Default |
|--------|-------------|---------|
| watchFolder | Folder to watch for scans | Required |
| serverUrl | CardFlow server URL | http://localhost:3000 |
| token | Your CardFlow JWT token | Required |
| pairingMode | How to pair front/back | sequential |
| holoMode | Enable holographic enhancements | false |
| brightnessBoost | Brightness adjustment (0-100) | 0 |
| autoRotateBack | Auto-rotate back images | true |
