# -*- coding: utf-8 -*-
import json
import docker

dc = docker.Client(base_url='unix://var/run/docker.sock')

for line in dc.build('./swf', rm=True):
    line = json.loads(line.decode())
    print(line)


image_id = line['stream'][19:19+12]
image = dc.get_image(image_id)
image_tar = open('/tmp/%s.tar' % image_id, 'wb')
image_tar.write(image.data)
image_tar.close()

dc.remove_image(image_id)
print('Complete building a image saved in /tmp/ folder.')
