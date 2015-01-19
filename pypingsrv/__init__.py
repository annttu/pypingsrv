import sys
if sys.version_info<(3,0,0):
    from pypingsrv import *
else:
    from pypingsrv.pypingsrv import *
