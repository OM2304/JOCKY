import { NextResponse } from 'next/server';
import { exec } from 'child_process';
import util from 'util';
import path from 'path';
import fs from 'fs';

const execAsync = util.promisify(exec);

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const frameworkRoot = fs.existsSync(path.join(process.cwd(), 'jocky'))
      ? process.cwd()
      : path.resolve(process.cwd(), '..');

    const cmd = 'python agents/byovd.py --demo --json';
    const { stdout, stderr } = await execAsync(cmd, {
      cwd: frameworkRoot,
    });

    if (!stdout && stderr) {
      console.error('[BYOVD Scanner API] Execution error:', stderr);
      return NextResponse.json(
        { success: false, error: stderr },
        { status: 500 }
      );
    }

    // Parse stdout JSON
    const data = JSON.parse(stdout.trim());
    return NextResponse.json({
      success: true,
      data,
    });
  } catch (error: unknown) {
    const errMsg = error instanceof Error ? error.message : String(error);
    console.error('[BYOVD Scanner API] Error:', errMsg);
    return NextResponse.json(
      { success: false, error: errMsg },
      { status: 500 }
    );
  }
}
