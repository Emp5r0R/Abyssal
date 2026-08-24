import { Camera, CameraOff } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useCallback, useEffect, useRef, useState } from "react";

interface DetectedBarcode {
  rawValue?: string;
}

interface BarcodeDetectorInstance {
  detect(source: CanvasImageSource): Promise<DetectedBarcode[]>;
}

interface BarcodeDetectorConstructor {
  new(options: { formats: string[] }): BarcodeDetectorInstance;
  getSupportedFormats?(): Promise<string[]>;
}

const SCAN_INTERVAL_MS = 180;
const SCAN_TIMEOUT_MS = 60_000;

export function DirectVerificationQr({
  token,
  onScanned,
}: {
  token: string;
  onScanned: (token: string) => void;
}) {
  const [scanning, setScanning] = useState(false);
  const [scanUnavailable, setScanUnavailable] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const timerRef = useRef<number | null>(null);
  const detectorRef = useRef<BarcodeDetectorInstance | null>(null);

  const stopScanner = useCallback(() => {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    timerRef.current = null;
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    detectorRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
    setScanning(false);
  }, []);

  useEffect(() => stopScanner, [stopScanner]);

  const startScanner = useCallback(async () => {
    if (scanning) {
      stopScanner();
      return;
    }
    const Detector = (globalThis as typeof globalThis & {
      BarcodeDetector?: BarcodeDetectorConstructor;
    }).BarcodeDetector;
    if (!Detector || !navigator.mediaDevices?.getUserMedia) {
      setScanUnavailable(true);
      return;
    }
    try {
      if (Detector.getSupportedFormats) {
        const supported = await Detector.getSupportedFormats();
        if (!supported.includes("qr_code")) throw new Error("Unavailable");
      }
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: "environment" } },
      });
      const video = videoRef.current;
      if (!video) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }
      streamRef.current = stream;
      detectorRef.current = new Detector({ formats: ["qr_code"] });
      video.srcObject = stream;
      await video.play();
      setScanning(true);
      setScanUnavailable(false);
      const deadline = performance.now() + SCAN_TIMEOUT_MS;
      const scan = async () => {
        if (!streamRef.current || !detectorRef.current || !videoRef.current) return;
        if (performance.now() >= deadline) {
          stopScanner();
          return;
        }
        try {
          const codes = await detectorRef.current.detect(videoRef.current);
          const value = codes.find((code) => code.rawValue)?.rawValue;
          if (value) {
            stopScanner();
            onScanned(value);
            return;
          }
        } catch {
          // A not-yet-ready video frame is retried until the bounded deadline.
        }
        timerRef.current = window.setTimeout(() => void scan(), SCAN_INTERVAL_MS);
      };
      timerRef.current = window.setTimeout(() => void scan(), SCAN_INTERVAL_MS);
    } catch {
      stopScanner();
      setScanUnavailable(true);
    }
  }, [onScanned, scanning, stopScanner]);

  return (
    <div className="direct-verification-qr">
      <div className="qr-image" role="img" aria-label="Direct chat verification QR code">
        <QRCodeSVG
          value={token}
          size={224}
          level="M"
          marginSize={1}
          bgColor="#f4fbff"
          fgColor="#05090d"
        />
      </div>
      <video
        ref={videoRef}
        className={scanning ? "verification-camera is-active" : "verification-camera"}
        muted
        playsInline
        aria-label="QR scanner preview"
      />
      <button className="secondary-button" type="button" onClick={() => void startScanner()}>
        {scanning ? <CameraOff size={16} /> : <Camera size={16} />}
        {scanning ? "STOP CAMERA" : "SCAN PEER QR"}
      </button>
      {scanUnavailable ? <p className="field-error" role="status">Camera scan unavailable. Paste the token below.</p> : null}
    </div>
  );
}
