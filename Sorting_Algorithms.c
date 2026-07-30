#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

#define RUNS 10000

//Generate random number arrays
void random_array(int arr[], int n){
	int i;
    for (i = 0; i < n; i++){
        arr[i] = rand() % 10000;
    }
}
//swap function
void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}
//----HEAP SORT----
void heapify(int arr[], int n, int i){
    int largest = i;        
    int left = 2 * i + 1;   
    int right = 2 * i + 2;   

    
    if (left<n && arr[left]>arr[largest]){
        largest = left;
    }

    if (right<n && arr[right]>arr[largest]){
        largest = right;
    }

    if (largest != i){
        swap(&arr[i], &arr[largest]);
        heapify(arr, n, largest);
    }
}

void heapSort(int arr[], int n) {
	int i;
    for (i = n / 2 - 1; i >= 0; i--) {
        heapify(arr, n, i);
    }

    for (i = n - 1; i > 0; i--) {
        swap(&arr[0], &arr[i]);

        heapify(arr, i, 0);
    }
}
//-----------------------------------------------------------------------------------------------------
//---MERGE SORT---

void merge_sorted_arrays(int a[], int l, int m, int r)
{
  int left_length = m - l + 1;
  int right_length = r - m;
  
  int temp_left[left_length];
  int temp_right[right_length];
 
  int i, j, k;
  
  for (i = 0; i < left_length; i++)
    temp_left[i] = a[l + i];
    
  for (i = 0; i < right_length; i++)
    temp_right[i] = a[m + 1 + i];
    
  for (i = 0, j = 0, k = l; k <= r; k++)
  {
    if ((i < left_length) &&
        (j >= right_length || temp_left[i] <= temp_right[j]))
    {
      a[k] = temp_left[i];
      i++;
    }
    else
    {
      a[k] = temp_right[j];
      j++;
    }
  }  
}
//
void merge_sort_recursion(int a[], int l, int r)
{
  if (l < r)
  {
    int m = l + (r - l) / 2;
    merge_sort_recursion(a, l, m);
    merge_sort_recursion(a, m + 1, r);
    merge_sorted_arrays(a, l, m, r);
  }
}

void merge_sort(int a[], int length)
{
  merge_sort_recursion(a, 0, length - 1);
}
//-----------------------------------------------------------------------------------------------------

//QUICK SORT--

int partition(int array[], int low, int high)
{
  int i,j;
  int pivot_index = high;
  if (pivot_index != high)
    swap(&array[pivot_index], &array[high]);
    
  int pivot_value = array[high];
  i = low; 
  for (j = low; j < high; j++)
  {
    if (array[j] <= pivot_value)
    {
      swap(&array[i], &array[j]);
      i++;
    }
  }
  swap(&array[i], &array[high]);
  return i;
}

void quicksort_recursion(int array[], int low, int high)
{
  if (low < high)
  {
    int pivot_index = partition(array, low, high);
    quicksort_recursion(array, low, pivot_index - 1);
    quicksort_recursion(array, pivot_index + 1, high);
  }
}

void quicksort(int array[], int length)
{
  quicksort_recursion(array, 0, length - 1);
}
//--------------------------------------------------------------------------------------------------

// Function to print array elements
void printArray(int arr[], int n) {
	int i;
    for (i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}


int main() {
	int n,r;
    srand((unsigned int)time(NULL)); 
    
    double total_c_heap = 0, total_c_merge = 0, total_c_quick = 0;
    int num_sizes = 0;

    printf("(%d runs per N)\n", RUNS);
    printf("=========================================================================\n");
    printf("%-5s | %-20s | %-20s | %-20s\n", "N", "HeapSort", "MergeSort", "QuickSort");
    printf("%-5s | %-9s | %-8s | %-9s | %-8s | %-9s | %-8s\n", "", "Time(s)", "Constant", "Time(s)", "Constant", "Time(s)", "Constant");
    printf("=========================================================================\n");

    for (n = 100; n <= 1000; n += 100) {
        int base_arr[1000];
        int test_arr[1000];
        random_array(base_arr, n);

        clock_t start;

        
        start = clock();
        for (r = 0; r < RUNS; r++) {
            memcpy(test_arr, base_arr, n * sizeof(int));
        }
        double time_overhead = (double)(clock() - start) / CLOCKS_PER_SEC;

        
        start = clock();
        for (r = 0; r < RUNS; r++) {
            memcpy(test_arr, base_arr, n * sizeof(int));
            heapSort(test_arr, n);
        }
        double time_heap = ((double)(clock() - start) / CLOCKS_PER_SEC) - time_overhead;

        
        start = clock();
        for (r = 0; r < RUNS; r++) {
            memcpy(test_arr, base_arr, n * sizeof(int));
            merge_sort(test_arr, n);
        }
        double time_merge = ((double)(clock() - start) / CLOCKS_PER_SEC) - time_overhead;


        start = clock();
        for (r = 0; r < RUNS; r++) {
            memcpy(test_arr, base_arr, n * sizeof(int));
            quicksort(test_arr, n);
        }
        double time_quick = ((double)(clock() - start) / CLOCKS_PER_SEC) - time_overhead;

    
        if (time_heap < 0) time_heap = 0;
        if (time_merge < 0) time_merge = 0;
        if (time_quick < 0) time_quick = 0;

        
        double n_log_n = n * (log(n) / log(2.0));

        double scale = 100000000.0; 
        double c_heap = ((time_heap / RUNS) / n_log_n) * scale;
        double c_merge = ((time_merge / RUNS) / n_log_n) * scale;
        double c_quick = ((time_quick / RUNS) / n_log_n) * scale;

        total_c_heap += c_heap;
        total_c_merge += c_merge;
        total_c_quick += c_quick;
        num_sizes++;

        printf("%-5d | %-9.5f | %-8.2f | %-9.5f | %-8.2f | %-9.5f | %-8.2f\n", 
               n, time_heap, c_heap, time_merge, c_merge, time_quick, c_quick);
    }

    printf("=========================================================================\n");
    printf("OVERALL AVERAGE CONSTANT (C):\n");
    printf("HeapSort : %.2f\n", total_c_heap / num_sizes);
    printf("MergeSort: %.2f\n", total_c_merge / num_sizes);
    printf("QuickSort: %.2f\n", total_c_quick / num_sizes);

    return 0;
}
