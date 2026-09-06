import { BarcodeFormat, QRCodeWriter } from "@zxing/library";
import { crc32, deflateSync } from "node:zlib";

// Fixed public test vector, never a production capability.
export const QR_TEST_INVITE = "abyssal:invite:glh3igFwb3JnLmFieXNzYWwuY2hhdAFYINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4UgozLJd4c3gYMBcG5vZGUuZXhhbXBsZS5jb20ZAbtYICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiCQoAGn0rdQBYQDgZJxVYJlrtgAJBj4VbdykqYpymbDWTNY0Uz-18fOOxGzi6fwKTPzEnVkJ6QldbfyY0pl1JJchNJv3TknkT-Qs";

export function qrPng(text = QR_TEST_INVITE, metadata?: string): Uint8Array {
  const side = 640;
  const matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, side, side, new Map());
  const pixels = Buffer.alloc((side + 1) * side);
  for (let y = 0; y < side; y++) for (let x = 0; x < side; x++) {
    pixels[y * (side + 1) + x + 1] = matrix.get(x, y) ? 0 : 255;
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(side, 0);
  header.writeUInt32BE(side, 4);
  header[8] = 8;
  return new Uint8Array(Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", header),
    ...(metadata ? [chunk("tEXt", Buffer.from(`Comment\0${metadata}`))] : []),
    chunk("IDAT", deflateSync(pixels)), chunk("IEND", Buffer.alloc(0)),
  ]));
}

function chunk(type: string, data: Buffer): Buffer {
  const name = Buffer.from(type);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, checksum]);
}
