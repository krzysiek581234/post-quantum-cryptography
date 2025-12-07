from queue import Queue
import threading

usb_path_queue = Queue()
usb_detected_event = threading.Event()

