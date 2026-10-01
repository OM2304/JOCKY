import { NextResponse } from 'next/server';
import { exec } from 'child_process';
import util from 'util';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';

const execAsync = util.promisify(exec);

export const dynamic = 'force-dynamic';

export async function POST() {
  return handlePolyExecution();
}

export async function GET() {
  return handlePolyExecution();
}

async function handlePolyExecution() {
  try {
    const frameworkRoot = fs.existsSync(path.join(process.cwd(), 'jocky'))
      ? process.cwd()
      : path.resolve(process.cwd(), '..');

    // Ensure output builds directory exists
    const buildsDir = path.join(frameworkRoot, 'builds');
    if (!fs.existsSync(buildsDir)) {
      fs.mkdirSync(buildsDir, { recursive: true });
    }

    const cmd = 'python -m jocky poly examples/stealth.jck -n 2 -o builds/';
    const { stdout, stderr } = await execAsync(cmd, {
      cwd: frameworkRoot,
    });

    if (!stdout && stderr) {
      console.error('[Polymorphic Engine] Execution error:', stderr);
      return NextResponse.json(
        { success: false, error: stderr },
        { status: 500 }
      );
    }

    // Parse stdout:
    // build 01: builds/stealth_b01.jcx  sha256=1272589539f6a520  2779B
    // build 02: builds/stealth_b02.jcx  sha256=d7a650f7ebefae5f  2795B
    const lineRegex = /build\s+(\d+):\s+([^\s]+)\s+sha256=([a-f0-9]+)\s+([0-9]+B)/gi;
    const variants = [];
    const hashes: string[] = [];
    const fullHashes: string[] = [];

    let match;
    while ((match = lineRegex.exec(stdout)) !== null) {
      const buildNum = match[1];
      const relPath = match[2];
      const shortHash = match[3];
      const byteSize = match[4];

      hashes.push(shortHash);

      // Compute full 64-char SHA-256 hash of the generated .jcx file
      let fullHash = shortHash;
      const fullPath = path.join(frameworkRoot, relPath);
      if (fs.existsSync(fullPath)) {
        const fileContent = fs.readFileSync(fullPath);
        fullHash = crypto.createHash('sha256').update(fileContent).digest('hex');
      }
      fullHashes.push(fullHash);

      variants.push({
        id: buildNum === '01' ? 'alpha' : 'beta',
        label: buildNum === '01' ? 'Variant Alpha' : 'Variant Beta',
        buildNumber: buildNum,
        file: path.basename(relPath),
        hash: shortHash,
        fullHash,
        size: byteSize,
      });
    }

    return NextResponse.json({
      success: true,
      timestamp: new Date().toISOString(),
      sourceScript: 'examples/stealth.jck',
      command: cmd,
      hashes,
      fullHashes,
      variants,
      uniqueCount: variants.length,
      stdout: stdout.trim(),
    });
  } catch (error: unknown) {
    const errMsg = error instanceof Error ? error.message : String(error);
    console.error('[Polymorphic Engine] Execution failure:', errMsg);
    return NextResponse.json(
      { success: false, error: errMsg },
      { status: 500 }
    );
  }
}
