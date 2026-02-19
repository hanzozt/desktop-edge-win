@echo off

IF "x%ZITI_CI_VERSION%"=="x" GOTO DEFAULT
SET GO111MODULE=on

echo Fetching zt-ci@%ZITI_CI_VERSION%
go get github.com/hanzozt/zt-ci@%ZITI_CI_VERSION% 2> NUL
GOTO END

:DEFAULT
echo Fetching default zt-ci
go get github.com/hanzozt/zt-ci 2> NUL
GOTO END

:END
echo go get of zt-ci complete
