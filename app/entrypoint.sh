#!/bin/sh

set -xe

# Start p0f in background
p0f -s /app/p0f.sock &

# start honeypot
python ./honeypot.py