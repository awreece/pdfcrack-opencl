pdfcrack-opencl
===============

An OpenCL pdfcracker implemented in python.

The binary is `run.py`, see `run.py --help` for more info.

Example usage: `python run.py -i order.pdf --use-gpu -u '' -v`

Currently I'm lazy, and require pdfcrack (http://pdfcrack.sourceforge.net/) to 
be installed so I can avoid parsing pdf files.

Note: it probably won't work if you're not in the same directory as run.py.

Note: you need to install the following libraries in order to use this:

    pip install pycrypto
    pip install numpy
    pip install pyopencl
