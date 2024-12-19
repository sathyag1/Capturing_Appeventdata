#!/bin/bash
echo "Starting App event data"
cd /opt/app
gunicorn --workers=1 -b 0.0.0.0:5000 Appeventdata:app --log-file=-
