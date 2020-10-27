def BellmanFord(weight,source):
	distance=[999999999]*len(weight)
	distance[source]=0
	parent=[0]*len(weight)
	parent[source]=source
	
	for i in range(0,len(weight)):
		for a in range(0,len(weight)):
			for b in range(0,len(weight)):
				if distance[a] != 999999999 and weight[a][b] != 999999999:
					if (distance[a] + weight[a][b]) < distance[b]:
						distance[b] = distance[a] + weight[a][b]
						parent[b] = a
	for a in range(0,len(weight)):
		for b in range(0,len(weight)):
			if distance[a] + weight[a][b] < distance[b]:
				sys.exit("Graph contains a negative-weight cycle")
	return ( distance , parent )

def MakeForwardingTable(weight):
	table=[]
	for i in range(0,len(weight)):
		table.append([0]*len(weight))
	distance=[]
	for i in range(0,len(weight)):
		distance.append([0]*len(weight))
	parent=[]
	for i in range(0,len(weight)):
		parent.append([0]*len(weight))
	
	for i in range(0,len(weight)):
		distance[i] , parent[i] = BellmanFord(weight,i)

	for i in range(0,len(weight)):
		for j in range(0,len(weight)):
			parentNode=j
			while parent[i][parentNode] != i:
				parentNode = parent[i][parentNode]
			table[i][j]=parentNode
	
	return (table,distance)


