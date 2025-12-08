from queue import Queue
import threading

usb_path_queue = Queue()
usb_detected_event = threading.Event()

last_private_seen = None
last_public_seen = None


skip_private_key = 0
skip_public_key = 0