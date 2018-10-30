import ipinfo
from math import sin, cos, sqrt, atan2, radians

class FraudDetection:
  def __init__(self, filename):
    access_token = '83b0fe641f4689'
    self.handler = ipinfo.getHandler(access_token)
    self.frauds = {}
    self.logins = {}
    self.ips = {}

    file = open(filename, 'r')
    lines = file.readlines()
    for line in lines:
      labelAndIp = line.split()
      ipAddress = labelAndIp[1]
      coordinates = self.handler.getDetails(ipAddress).loc

      #If this ip address has been marked as a fraud before, it should always be fraud
      if ipAddress not in self.ips || labelAndIp[1] == 'FRAUD':
        self.ips[ipAddress] = (coordinates, labelAndIp[0])

  def score(self, ip):
    coordinates = self.handler.getDetails(ip).loc
    minDistance = float("inf")
    closestIp = ""

    for key in self.ips:
      distance = self.distanceBetweenCoordinates(coordinates, self.ips[key][0])
      if distance < minDistance:
        minDistance = distance
        closestIp = key

    if self.ips[closestIp][1] == 'FRAUD':
      return 2*minDistance
    else:
      return minDistance

  #Haversine formula 
  def distanceBetweenCoordinates(self,first, second):
    lat1,lon1 = tuple(map(float, first.split(',')))
    lat2,lon2 = tuple(map(float, second.split(',')))

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = 3959.0 * c

    return distance

# fraudDetect = FraudDetection('UserRecords.txt')
# print(fraudDetect.score('103.35.242.155'))