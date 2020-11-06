class ValidationError(Exception):
    """
    Error in validation stage
    """
    pass

class RequestError(Exception):
    """
    Error in API request
    """
    def __init__(self, message=None):
        # If you need to raise a generic RequestError with a custom message,
        # use this constructor. Otherwise you can use error_for_code.
        if message is not None:
            self.message = message

    def __str__(self):
        return self.message

class EINTERNAL(RequestError):
    code = -1
    message = (
        'An internal error has occurred. Please submit a bug report, detailing '
        'the exact circumstances in which this error occurred'
    )

class EARGS(RequestError):
    code = -2
    message = 'You have passed invalid arguments to this command'

class EAGAIN(RequestError):
    code = -3
    message = (
        '(always at the request level) A temporary congestion or server '
        'malfunction prevented your request from being processed. No data was '
        'altered. Retry. Retries must be spaced with exponential backoff'
    )

class ERATELIMIT(RequestError):
    code = -4
    message = (
        'You have exceeded your command weight per time quota. Please wait a '
        'few seconds, then try again (this should never happen in sane '
        'real-life applications)'
    )

class EFAILED(RequestError):
    code = -5
    message = 'The upload failed. Please restart it from scratch'

class ETOOMANY(RequestError):
    code = -6
    message = (
        'Too many concurrent IP addresses are accessing this upload target URL'
    )

class ERANGE(RequestError):
    code = -7
    message = (
        'The upload file packet is out of range or not starting and ending on '
        'a chunk boundary'
    )

class EEXPIRED(RequestError):
    code = -8
    message = (
        'The upload target URL you are trying to access has expired. Please '
        'request a fresh one'
    )

class ENOENT(RequestError):
    code = -9
    message = 'Object (typically, node or user) not found'

class ECIRCULAR(RequestError):
    code = -10
    message = 'Circular linkage attempted'

class EACCESS(RequestError):
    code = -11
    message = 'Access violation (e.g., trying to write to a read-only share)'

class EEXIST(RequestError):
    code = -12
    message = 'Trying to create an object that already exists'

class EINCOMPLETE(RequestError):
    code = -13
    message = 'Trying to access an incomplete resource'

class EKEY(RequestError):
    code = -14
    message = 'A decryption operation failed (never returned by the API)'

class ESID(RequestError):
    code = -15
    message = 'Invalid or expired user session, please relogin'

class EBLOCKED(RequestError):
    code = -16
    message = 'User blocked'

class EOVERQUOTA(RequestError):
    code = -17
    message = 'Request over quota'

class ETEMPUNAVAIL(RequestError):
    code = -18
    message = 'Resource temporarily not available, please try again later'

class ETOOMANYCONNECTIONS(RequestError):
    code = -19
    message = 'many connections on this resource'

class EWRITE(RequestError):
    code = -20
    message = 'Write failed'

class EREAD(RequestError):
    code = -21
    message = 'Read failed'

class EAPPKEY(RequestError):
    code = -22
    message = 'Invalid application key; request not processed'

class EPAYWALL(RequestError):
    code = -29
    message = 'Over Disk Quota Paywall is blocking this operation'

_CODE_TO_CLASSES = {
    -1: EINTERNAL,
    -2: EARGS,
    -3: EAGAIN,
    -4: ERATELIMIT,
    -5: EFAILED,
    -6: ETOOMANY,
    -7: ERANGE,
    -8: EEXPIRED,
    -9: ENOENT,
    -10: ECIRCULAR,
    -11: EACCESS,
    -12: EEXIST,
    -13: EINCOMPLETE,
    -14: EKEY,
    -15: ESID,
    -16: EBLOCKED,
    -17: EOVERQUOTA,
    -18: ETEMPUNAVAIL,
    -19: ETOOMANYCONNECTIONS,
    -20: EWRITE,
    -21: EREAD,
    -22: EAPPKEY,
    -29: EPAYWALL,
}

def error_for_code(code):
    cls = _CODE_TO_CLASSES[code]
    return cls()
