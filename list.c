#include "list.h"
#include <stdlib.h>

node* cons(void *element, node* l)
{
	node* temp = malloc(sizeof(struct node));
	temp->element = element;
	temp->next = l;
	return temp;
}

node* cdr_and_free(node* l)
{
	node* temp = l->next; 
	free(l);
	return temp;
}