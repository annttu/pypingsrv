# PyPingSrv


Pure Python ping server.

## Installation

Using pip

    pip install --find-links http://code.annttu.fi/pip pypingsrv

## Usage


See example.py for example usage.

### Callback functions

```on_response(destination, data)``` callback function gets two arguments.

1. destination is ping destination as given to ping function.
2. data is dictionary containing information about packet. data fields are code: int, seq: int, checksum: int, time: float (in ms), type: int and id: int.


```on_packetloss(destination, timestamp)``` callback function gets two arguments.

1. destination is ping destination as given to ping function.
2. timestamp is timestamp when packetloss have occured.

### Logging

Pypingsrv uses PingServer logging facility.

## Author

* Antti 'Annttu' Jaakkola


## License

The MIT License (MIT)

Copyright (c) 2014 Antti Jaakkola

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
