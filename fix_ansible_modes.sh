#!/bin/bash

find . -type f -name "*.y*ml" -exec sed -i 's/\(mode: \)\(0[0-7]\{3\}\)\b/\1"\2"/g' {} +
#find . -type f -name "*.yaml" -exec sed -i 's/\(mode: \)\(0[0-7]\{3\}\)\b/\1"\2"/g' {} +
