#coding=UTF-8

bind = '0.0.0.0:8000' #绑定的端口
workers = 1 #worker数量
backlog = 2048
debug = True
proc_name = 'gunicorn.pid'
pidfile = '/home/xiaoyue/anaconda3/lib/python3.7/site-packages/gunicorn/debug.log'
loglevel = 'debug'
