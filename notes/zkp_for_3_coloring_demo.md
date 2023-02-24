# Session 1 - ZKP for 3-coloring Demo

> Visit http://web.mit.edu/~ezyang/Public/graph/svg.html and play around with the interactive demo. This is a programmatic version of the 3-coloring example we went over in class.
> 
> Answer Exercise 1 at the bottom of the page.

## Exercise 1

> Q: Currently, you can only select adjacent pairs of nodes to check. Would the proof still be zero knowledge if you could pick arbitrary pairs of nodes to check?

Answer:

No. We could select a node `A` and query each pair with all other nodes once a time. After that all nodes that is the same color with node `A` is known to us. Doing this for all nodes we could reveal the origin map. 


