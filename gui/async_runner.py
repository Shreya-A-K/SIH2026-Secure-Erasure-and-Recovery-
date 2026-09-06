"""
async_runner.py — Thread-safe asynchronous worker for Tkinter.

Avoids Tkinter thread violations by using a thread-safe queue.Queue.
Worker threads only interact with Python queues; all UI callbacks are
executed safely on the Tkinter main thread.
"""

import queue
import threading


class AsyncRunner:
    def __init__(self, widget):
        self.widget = widget
        self.queue = queue.Queue()
        self._running = True
        self._poll()

    def _poll(self):
        if not self._running:
            return
        try:
            while True:
                fn, args, kwargs = self.queue.get_nowait()
                try:
                    fn(*args, **kwargs)
                except Exception as e:
                    print(f"[AsyncRunner] Callback error: {e}")
        except queue.Empty:
            pass
        except Exception:
            pass

        try:
            self.widget.after(40, self._poll)
        except Exception:
            # Widget destroyed
            self._running = False

    def run(self, task_fn, on_complete=None, on_error=None):
        """Runs task_fn in a background daemon thread, returning result to on_complete."""
        def worker():
            try:
                res = task_fn()
                if on_complete:
                    self.queue.put((on_complete, (res,), {}))
            except Exception as e:
                if on_error:
                    self.queue.put((on_error, (str(e),), {}))
                else:
                    print(f"[AsyncRunner] Task exception: {e}")

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return t

    def stop(self):
        self._running = False
