import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'child_process';
import util from 'util';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';

const execAsync = util.promisify(exec);

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { targetNode = 'local-workstation-01', scriptName = 'triage' } = body;

    // Sanitize script name to avoid path traversal / command injection
    const allowedScripts = [
      'triage',
      'netprobe',
      'stealth',
      'ioc_sweep',
      'lateral_recon',
      'sandbox_guard',
      'hello',
    ];
    const safeScript = allowedScripts.includes(scriptName) ? scriptName : 'triage';

    // Sanitize target node name (allow alphanumeric, hyphens, underscores, dots)
    const safeTarget = String(targetNode).replace(/[^a-zA-Z0-9_\-.]/g, '') || 'local-workstation-01';

    // Determine the working directory (root of the JOCKY framework)
    const frameworkRoot = fs.existsSync(path.join(process.cwd(), 'jocky'))
      ? process.cwd()
      : path.resolve(process.cwd(), '..');

    // 1. Resolve encryption key: use process.env.JOCKY_KEY with fallback to default master key
    const key = process.env.JOCKY_KEY || '00112233445566778899aabbccddeeff';

    // 2. Generate a unique task tag
    const tag = `task-${Date.now()}`;

    // 3. Command 1: Compile & Encrypt payload with explicit key
    const encCmd = `python -m jocky enc examples/${safeScript}.jck -o payload.jxp -k ${key}`;
    const { stdout: encStdout, stderr: encStderr } = await execAsync(encCmd, {
      cwd: frameworkRoot,
    });

    if (encStderr && !encStdout) {
      console.error('[JOCKY Dispatch] Compilation error:', encStderr);
      return NextResponse.json(
        { success: false, error: `Payload encryption failed: ${encStderr}` },
        { status: 500 }
      );
    }

    // 4. Command 2: Queue Task on the Central Controller
    const addCmd = `python -m agents.controller add payload.jxp --tag ${tag}`;
    const { stdout: addStdout, stderr: addStderr } = await execAsync(addCmd, {
      cwd: frameworkRoot,
    });

    if (addStderr && !addStdout) {
      console.error('[JOCKY Dispatch] Controller task queue error:', addStderr);
      return NextResponse.json(
        { success: false, error: `Controller task queueing failed: ${addStderr}` },
        { status: 500 }
      );
    }

    // Extract Task ID from controller output (e.g., "task 92c5f62d2d2a ...")
    const taskIdMatch = addStdout.match(/task\s+([a-f0-9]{12})/i);
    const taskId = taskIdMatch ? taskIdMatch[1] : undefined;

    // 5. Command 3: Execute Agent in RAM with JOCKY_KEY in process environment
    const taskFlag = taskId ? ` --task ${taskId}` : '';
    const clientCmd = `python -m agents.client --controller http://127.0.0.1:8177 --agent-name ${safeTarget}${taskFlag} --once`;
    const { stdout: clientStdout, stderr: clientStderr } = await execAsync(clientCmd, {
      cwd: frameworkRoot,
      env: {
        ...process.env,
        JOCKY_KEY: key,
      },
    });

    return NextResponse.json({
      success: true,
      message: 'Forensic task successfully dispatched and executed in RAM.',
      task: taskId,
      tag,
      targetNode: safeTarget,
      scriptName: safeScript,
      key,
      compileOutput: encStdout?.trim(),
      controllerOutput: addStdout?.trim(),
      clientOutput: clientStdout?.trim(),
    });
  } catch (error: unknown) {
    const errMsg = error instanceof Error ? error.message : String(error);
    console.error('[JOCKY Dispatch] Execution error:', errMsg);
    return NextResponse.json(
      {
        success: false,
        error: errMsg || 'Failed to dispatch forensic task to target agent.',
      },
      { status: 500 }
    );
  }
}
