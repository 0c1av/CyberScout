paths_list = []
for year in range(2000, 2025):
	paths_list.append(f"{year}/")
	for month in range(1, 13):
		paths_list.append(f"{year}/{month:02d}/")
		for day in range(1, 32):
			paths_list.append(f"{year}/{month:02d}/{day:02d}/")
