import logging
import os
import time
from datetime import datetime

class Logs:
    def __init__(self, apikey):
        self.apikey = apikey

        # 로그 파일을 저장할 디렉토리 경로를 설정합니다.
        logDir = 'logs'

        # 로그 디렉토리가 존재하지 않으면 생성합니다.
        if not os.path.exists(logDir):
            os.makedirs(logDir)

        # 현재 날짜를 기반으로 로그 파일명을 생성합니다.
        logFilename = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

        # 로그 파일의 전체 경로를 생성합니다.
        logFilePath = os.path.join(logDir, logFilename)

        # 로깅 설정을 구성합니다.
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s]: %(message)s',
            handlers=[
                logging.FileHandler(logFilePath),
                logging.StreamHandler()
            ]
        )
    
    def debug(self, message):
        logging.debug(message)

    def info(self, message):
        logging.info(message)

    def warning(self, message):
        logging.warning(message)

    def error(self, message):
        logging.error(message)

    def critical(self, message):
        logging.critical(message)
