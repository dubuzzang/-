const QRCode = require('qrcode');
const sharp = require('sharp');

async function addQrWatermark(imageInput, linkUrl) {
  let imageBuffer;
  if (typeof imageInput === 'string') {
    const res = await fetch(imageInput);
    imageBuffer = Buffer.from(await res.arrayBuffer());
  } else {
    imageBuffer = imageInput;
  }

  const image = sharp(imageBuffer);
  const metadata = await image.metadata();
  const width = metadata.width;
  const height = metadata.height;

  // QR코드: 배경 없이(투명), 무늬는 선명한 흰색. 오류 정정 레벨은 H(가장 튼튼)로 해서 스캔이 잘 되게 함
  const qrBuffer = await QRCode.toBuffer(linkUrl, {
    width: 500,
    margin: 0,
    errorCorrectionLevel: 'H',
    color: {
      dark: '#FFFFFFFF',
      light: '#00000000'
    }
  });

  const targetWidth = Math.floor(width * 0.7);
  const qrResized = await sharp(qrBuffer).resize(targetWidth, targetWidth).toBuffer();

  const left = Math.floor((width - targetWidth) / 2);
  const top = Math.floor((height - targetWidth) / 2);

  // 스캔이 잘 되려면 QR 주변에 여백(quiet zone)과, 사진 색과 상관없이 대비를 만들어주는 반투명 배경판이 필요해요
  const quiet = Math.round(targetWidth * 0.15);
  const panelSize = targetWidth + quiet * 2;
  const panelLeft = Math.max(0, left - quiet);
  const panelTop = Math.max(0, top - quiet);
  const panelSvg = `
    <svg width="${panelSize}" height="${panelSize}">
      <rect x="0" y="0" width="${panelSize}" height="${panelSize}" rx="${Math.round(panelSize * 0.04)}" fill="#000000" fill-opacity="0.7"/>
    </svg>
  `;
  const panelBuffer = Buffer.from(panelSvg);

  // QR코드 밑에 넣을 아이디 텍스트
  const fontSize = Math.floor(width * 0.05);
  const textSvg = `
    <svg width="${width}" height="${fontSize + 20}">
      <text x="50%" y="${fontSize}" font-size="${fontSize}" font-family="sans-serif" font-weight="bold"
        fill="#FFFFFF" fill-opacity="0.9" text-anchor="middle"
        stroke="#000000" stroke-opacity="0.35" stroke-width="1">
        @_dubu_zzang
      </text>
    </svg>
  `;
  const textBuffer = Buffer.from(textSvg);
  const textTop = Math.min(top + targetWidth + 10, height - fontSize - 20);

  const outputBuffer = await image
    .composite([
      { input: panelBuffer, left: panelLeft, top: panelTop },
      { input: qrResized, left, top },
      { input: textBuffer, left: 0, top: Math.max(textTop, 0) }
    ])
    .jpeg()
    .toBuffer();

  return 'data:image/jpeg;base64,' + outputBuffer.toString('base64');
}

module.exports = { addQrWatermark };
