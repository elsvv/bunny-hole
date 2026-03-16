// src/compress.ts

export interface CompressResult {
  data: Uint8Array;
  mimeType: string;
  originalSize: number;
  compressedSize: number;
}

const MIN_COMPRESS_SIZE = 50 * 1024; // 50 KB
const SKIP_TYPES = new Set(['image/gif', 'image/svg+xml']);

export type ImageQuality = 'low' | 'medium' | 'high';

const QUALITY_PRESETS: Record<ImageQuality, { quality: number; maxDim: number }> = {
  low:    { quality: 0.25, maxDim: 1024 },
  medium: { quality: 0.5,  maxDim: 1440 },
  high:   { quality: 0.7,  maxDim: 1920 },
};

/** Returns true if the file is a compressible image (image/* but not gif/svg, and >= 50 KB). */
export function shouldCompress(file: File): boolean {
  if (!file.type.startsWith('image/')) return false;
  if (SKIP_TYPES.has(file.type)) return false;
  return file.size >= MIN_COMPRESS_SIZE;
}

/** Read any File into a Uint8Array. */
export async function fileToUint8Array(file: File): Promise<Uint8Array> {
  const buf = await file.arrayBuffer();
  return new Uint8Array(buf);
}

/** Compress an image file using Canvas API. Returns original data as-is for non-compressible files. */
export async function compressImage(file: File, level: ImageQuality = 'high'): Promise<CompressResult> {
  const originalSize = file.size;

  if (!shouldCompress(file)) {
    const data = await fileToUint8Array(file);
    return { data, mimeType: file.type || 'application/octet-stream', originalSize, compressedSize: originalSize };
  }

  const preset = QUALITY_PRESETS[level];
  const img = await loadImage(file);
  const { width, height } = targetDimensions(img.naturalWidth, img.naturalHeight, preset.maxDim);

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d')!;
  ctx.drawImage(img, 0, 0, width, height);

  // Try WebP first, fall back to JPEG
  let blob = await canvasToBlob(canvas, 'image/webp', preset.quality);
  let mimeType = 'image/webp';

  if (!blob) {
    blob = await canvasToBlob(canvas, 'image/jpeg', preset.quality);
    mimeType = 'image/jpeg';
  }

  // If compression made it larger, return original
  if (!blob || blob.size >= originalSize) {
    const data = await fileToUint8Array(file);
    return { data, mimeType: file.type, originalSize, compressedSize: originalSize };
  }

  const data = new Uint8Array(await blob.arrayBuffer());
  return { data, mimeType, originalSize, compressedSize: data.byteLength };
}

function loadImage(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Failed to load image'));
    };
    img.src = url;
  });
}

function targetDimensions(w: number, h: number, maxDim: number): { width: number; height: number } {
  if (w <= maxDim && h <= maxDim) return { width: w, height: h };
  const scale = Math.min(maxDim / w, maxDim / h);
  return { width: Math.round(w * scale), height: Math.round(h * scale) };
}

function canvasToBlob(canvas: HTMLCanvasElement, type: string, quality: number): Promise<Blob | null> {
  return new Promise((resolve) => {
    canvas.toBlob((blob) => resolve(blob), type, quality);
  });
}
