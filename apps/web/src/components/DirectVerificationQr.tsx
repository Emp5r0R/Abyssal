import { Camera } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useCallback, useState } from "react";
import { QrScanner } from "./QrScanner";
import { QrImageInput } from "./QrImageInput";

export function DirectVerificationQr({ token, onScanned }: {
  token: string;
  onScanned: (token: string) => void;
}) {
  const [scanning, setScanning] = useState(false);
  const accept = useCallback(async (value: string, signal: AbortSignal) => {
    if (signal.aborted || !/^abyssal:verify:v1:[A-Za-z0-9_-]{43}$/u.test(value)) return false;
    onScanned(value);
    setScanning(false);
    return true;
  }, [onScanned]);
  return (
    <div className="direct-verification-qr">
      <div className="qr-image" role="img" aria-label="Direct chat verification QR code">
        <QRCodeSVG value={token} size={224} level="M" marginSize={1} bgColor="#f4fbff" fgColor="#05090d" />
      </div>
      {scanning ? <QrScanner onScanned={accept} onClose={() => setScanning(false)} /> : (
        <button className="secondary-button" type="button" onClick={() => setScanning(true)}>
          <Camera size={16} /> SCAN PEER QR
        </button>
      )}
      <QrImageInput disabled={scanning} onScanned={accept} />
    </div>
  );
}
