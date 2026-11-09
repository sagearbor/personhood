// Non-visual cues for the selfie ceremony: speech, a tone and a vibration
// when each challenge starts and when it passes.
//
// Why: during "turn your head" the person is looking away from the screen,
// so a text prompt alone cannot be read (Pixel 10 test, 2026-11-04). Each
// prompt is spoken, a distinct tone and buzz mark "start" and "passed", and
// after a head turn the app says "look back at the screen". The same cues
// make the ceremony usable with low vision.
//
// cuesFor() is pure (tested); browserCues() plays the result with the Web
// Speech API, Web Audio and navigator.vibrate, each best effort: a browser
// without one of them just skips it.

import { PROMPTS, type ChallengeKind, type Phase } from './liveness';

export type Tone = 'start' | 'pass' | 'fail' | 'done';

export type Cue = {
  /** Text to speak, if any. */
  say?: string;
  tone?: Tone;
  /** navigator.vibrate pattern, in ms. */
  vibrate?: number[];
};

export const VIBRATE: Record<Tone, number[]> = {
  start: [90],
  pass: [40, 60, 40],
  fail: [300],
  done: [40, 60, 40, 60, 120],
};

/** Spoken after a challenge passes; turns also ask the person to look back. */
export function passedText(kind: ChallengeKind): string {
  return kind === 'turn_left' || kind === 'turn_right' ? 'Good. Look back at the screen.' : 'Good.';
}

/**
 * The cues for one phase change. `passed` is the challenge that just
 * completed, if any. Returns [] when nothing changed.
 */
export function cuesFor(prev: Phase | null, next: Phase, passed?: ChallengeKind): Cue[] {
  if (prev && samePhase(prev, next)) return [];
  const out: Cue[] = [];
  if (passed) out.push({ say: passedText(passed), tone: 'pass', vibrate: VIBRATE.pass });
  switch (next.kind) {
    case 'frontal':
      out.push({
        say: next.which === 'start' ? 'Look straight at the camera.' : 'Look straight at the camera again.',
        ...(next.which === 'start' ? { tone: 'start' as const, vibrate: VIBRATE.start } : {}),
      });
      break;
    case 'challenge':
      out.push({ say: PROMPTS[next.challenge] + '.', tone: 'start', vibrate: VIBRATE.start });
      break;
    case 'done':
      out.push({ say: 'Done. You can look at the screen.', tone: 'done', vibrate: VIBRATE.done });
      break;
    case 'failed':
      out.push({ say: 'Stopped. Look at the screen.', tone: 'fail', vibrate: VIBRATE.fail });
      break;
  }
  return out;
}

function samePhase(a: Phase, b: Phase): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'frontal' && b.kind === 'frontal') return a.which === b.which;
  if (a.kind === 'challenge' && b.kind === 'challenge') return a.index === b.index;
  return true;
}

/** Edge arrow for a challenge: which screen edge, as seen in the mirrored preview. */
export function arrowFor(p: Phase): 'left' | 'right' | null {
  if (p.kind !== 'challenge') return null;
  // The preview is mirrored, so turning to your own left moves your face
  // toward the left of the screen.
  if (p.challenge === 'turn_left') return 'left';
  if (p.challenge === 'turn_right') return 'right';
  return null;
}

export type CuePlayer = {
  /** Call from the click that starts the ceremony: browsers only allow audio after a gesture. */
  prime(): void;
  play(cues: Cue[]): void;
  stop(): void;
};

const TONES: Record<Tone, number[]> = {
  start: [660, 880],
  pass: [1320],
  fail: [300, 220],
  done: [660, 880, 1320],
};

/** Plays cues in the browser; every part is optional. */
export function browserCues(lang = 'en-US'): CuePlayer {
  let audio: AudioContext | null = null;
  const synth = typeof window !== 'undefined' ? window.speechSynthesis : undefined;

  function beep(tone: Tone) {
    if (!audio) return;
    const t0 = audio.currentTime;
    TONES[tone].forEach((hz, i) => {
      const osc = audio!.createOscillator();
      const gain = audio!.createGain();
      osc.frequency.value = hz;
      gain.gain.setValueAtTime(0.0001, t0 + i * 0.12);
      gain.gain.exponentialRampToValueAtTime(0.25, t0 + i * 0.12 + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + i * 0.12 + 0.1);
      osc.connect(gain).connect(audio!.destination);
      osc.start(t0 + i * 0.12);
      osc.stop(t0 + i * 0.12 + 0.11);
    });
  }

  return {
    prime() {
      try {
        const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
        if (Ctx && !audio) audio = new Ctx();
        void audio?.resume();
      } catch {
        audio = null;
      }
      try {
        // An empty utterance inside the gesture unlocks speech on mobile browsers.
        synth?.speak(new SpeechSynthesisUtterance(''));
      } catch {
        /* no speech */
      }
    },
    play(cues) {
      for (const c of cues) {
        if (c.tone) {
          try {
            beep(c.tone);
          } catch {
            /* no audio */
          }
        }
        if (c.vibrate) {
          try {
            navigator.vibrate?.(c.vibrate);
          } catch {
            /* no vibration */
          }
        }
        if (c.say && synth) {
          try {
            const u = new SpeechSynthesisUtterance(c.say);
            u.lang = lang;
            u.rate = 1.05;
            synth.speak(u);
          } catch {
            /* no speech */
          }
        }
      }
    },
    stop() {
      try {
        synth?.cancel();
      } catch {
        /* ignore */
      }
    },
  };
}
