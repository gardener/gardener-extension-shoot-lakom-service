# Steps for local development


## Changes needed for deploying the seed pods
1. Create the "lakom-extension" namespace

2. Fix the charts/images.yaml file. 
Add:
tag: v0.13.0-dev-7304248b35e6704cfe14b8debdbd54fb839b492e

Ще извикваме ли kind push <image> за да качим конкретния image?

3. Fix the chars/images.yaml file
Should be "snapshots" instead of "releases"

## Steps to deploy the admission webhooks for the shoot
1. Apply example/controller-registration.yaml file
