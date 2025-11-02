from queue import Queue
import threading

usb_path_queue = Queue()
usb_detected_event = threading.Event()
correctPassword = False
key_password = None
path_public_key = None
path_private_key = None

foundUSB = False
GL_private_key = None
GL_public_key = None
XML_path = None
file_path = None
public_key = None