__author__ = 'IBM'

# (C) Copyright IBM Corp. 2018 All Rights Reserved

from app import app
from app.gpylib import gpylib

# gpylib.create_log()
app.run(debug=True, host='0.0.0.0')
