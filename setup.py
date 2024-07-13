from setuptools import setup, find_packages

from FuxuanTracer.__metadata__ import (
    __version__,
    __author__, 
    __packageName__,
    __requirePath__,
    __license__,
    __readmePath__,
    __githubURL__
    )

def load_requirements(filepath: str = __requirePath__) -> list[str]:
    try:
       with open(filepath, 'r') as f:
           return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        return []
    except Exception as e:
        return []
    
# 记录更新日志

setup(
    name=__packageName__,
    version=__version__,
    packages=find_packages(),
    author=__author__,
    author_email='3072252442@qq.com',
    description='A useful logging library for Python',
    long_description=open(__readmePath__,'r',encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    url=__githubURL__,
    requires=load_requirements(),  # 依赖
    license=__license__,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
