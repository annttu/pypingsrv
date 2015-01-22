from pypingsrv import PingServer
import logging
import time

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger("PingServer").setLevel(logging.WARNING)
x = None

def on_packetloss(dest, x):
    print("Packetloss %s at %s" % (dest, x))

def on_success(dest, x):
    print("Success %s: %s ms" % (dest, x['time']))


if __name__ == '__main__':
    logger = logging.getLogger("pinger")
    try:
        x = PingServer()
        x.start()
        x.ping("annttu.fi", interval=1, on_packetloss=on_packetloss, on_response=on_success)
        while True:
            time.sleep(9999999)
    except KeyboardInterrupt:
        if x:
            x.stop()
    except Exception:
        logger.exception("Unhandled exception e")
        if x:
            x.stop()


