"""Audio capture module (EXPERIMENTAL). Records short audio clips via Windows winmm."""

from __future__ import annotations

import ctypes
import os
import time

IS_WINDOWS = os.name == "nt"


def record_clip(seconds: int = 5, output_wav: str = "") -> str:
    """Record an audio clip using winmm mciSendString (experimental)."""
    if not IS_WINDOWS:
        return "error: non-Windows platform"
    try:
        winmm = ctypes.windll.winmm
        winmm.mciSendStringW("open new type waveaudio alias recsound", None, 0, 0)
        winmm.mciSendStringW("set recsound time format ms bitspersample 16 channels 1 samplespersec 16000", None, 0, 0)
        winmm.mciSendStringW("record recsound", None, 0, 0)
        time.sleep(seconds)
        winmm.mciSendStringW("stop recsound", None, 0, 0)
        if not output_wav:
            output_wav = os.path.join(os.environ.get("LOCALAPPDATA", "C:\\"), "Temp", "audio_clip.wav")
        os.makedirs(os.path.dirname(output_wav), exist_ok=True)
        winmm.mciSendStringW(f'save recsound "{output_wav}"', None, 0, 0)
        winmm.mciSendStringW("close recsound", None, 0, 0)
        return output_wav if os.path.exists(output_wav) else "error: file not written"
    except Exception as e:
        return f"error: {e}"
