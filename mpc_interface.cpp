program.p
n = 100
k = 3  

x = Array(n, sint)
for i in range(n):
    x[i] = sint.get_input_from(0)

centroids = Array(k, sint)
for j in range(k):
    centroids[j] = x[j]

for i in range(n):
    min_dist = sint(1e9)
    best_cluster = sint(0)

    for j in range(k):
        diff = x[i] - centroids[j]
        dist = diff * diff
        is_closer = dist < min_dist
        min_dist = sint.if_else(is_closer, dist, min_dist)
        best_cluster = sint.if_else(is_closer, j, best_cluster)

    print_ln("Threat %s assigned to cluster %s", i, best_cluster)
