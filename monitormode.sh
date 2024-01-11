#!/bin/bash

# 네트워크 인터페이스를 비활성화
sudo ifconfig wlx588694fa3d0e down

# 네트워크 인터페이스를 모니터 모드로 설정
sudo iwconfig wlx588694fa3d0e mode monitor

# 네트워크 인터페이스를 다시 활성화
sudo ifconfig wlx588694fa3d0e up
