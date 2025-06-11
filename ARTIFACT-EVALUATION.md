# Artifact Appendix

Paper title: **HyDia: FHE-based Facial Matching with Hybrid Approximations and Diagonalization**

Artifacts HotCRP Id: **#Artifact2025.4 #33** 

Requested Badge: Either **Reproduced**

## Description
A short description of your artifact and how it links to your paper.

### Security/Privacy Issues and Ethical Concerns (All badges)
The artifact holds no risk to the security or privacy of the reviewer's machine.
There is no ethical concerns regarding the artifacts submitted here.

## Basic Requirements (Only for Functional and Reproduced badges)

### Hardware Requirements
Our artifact do not require specific hardware to be executed. All tests were run on a server with an Intel Xeon Gold 5412U processor, 128GB
RAM and 48 logical cores.


### Software Requirements
We recommend using an Linux OS version later than Ubuntu 20.04 to run this artifact. The primary dependencies, including OpenFHE and the required Python libraries, will be automatically configured during the Docker image build process. It is necessary to have Docker installed on the machine used for testing.


### Estimated Time and Storage Consumption
The artifact is expected to require less than 40 GB of disk space. The total execution time should be under 2 hours.

## Environment 
The environment should be automatically configured within the Docker container, provided the instructions in the README file are followed correctly. Step 4, titled “Using a Larger Database (Optional) and Other Features”, is not required for the artifact to run. However, it may be useful for users interested in comparing our method with alternative approaches or exploring additional functionality.


### Accessibility (All badges)
Our artifact can be access using the main branch of the GitHub link provided in the paper and artifact submission website.


### Set up the environment (Only for Functional and Reproduced badges)
Reviewers are advised to follow the instructions provided in the README.md file. Specifically, completing Steps (1), (2), and (3) will set up the Docker image along with the dependencies, execute the tests, and generate the figures included in the main manuscript.

The final output should consist of five figures generated in the directory ```~/artifact_output/manuscript_figures```. These figures correspond to those presented in the main manuscript.


### Testing the Environment (Only for Functional and Reproduced badges)

If the Docker image builds successfully without errors, the environment should be correctly configured for testing. Please note that both building and running the Docker container may require sudo privileges.


## Artifact Evaluation (Only for Functional and Reproduced badges)

### Main Results and Claims
HyDia is the most viable FHE-based approach in common bandwidth settings (2Mbps & 1Gbps), outperforming the state-of-the-art approaches by 5.2x-227.4x in end-to-end latency under different settings.

#### Main Result 1: HyDia is the fastest protocol under low bandwidth settings.
In Section 7.2 and Figure 6, we can note that HyDia’s average membership computation time is 102.41s and average identification computation time is 96.52s
for a 2^20 sized database. Hence, HyDia is faster than all four state-of-the-art approaches, demonstrating significant performance improvements over the baseline, GROTE, Blind-Match and HERS approaches in both the membership and identification scenarios across all database sizes


### Experiments 
To reproduce the results shown in Figure 6, reviewers must build and execute the Docker image by following the instructions provided in the README.md file. This process will generate the corresponding figures, which visually demonstrate that HyDia outperforms all other state-of-the-art methods in terms of end-to-end latency.
The entire process—including building the Docker image, executing the scripts, and generating the figures—should take less than 2 hours. The total disk space required is estimated to be under 40 GB.


## Limitations (Only for Functional and Reproduced badges)
The code above only reproduce the graphs based on the data over a subset of the the FRGC 2.0 RGB dataset and is located inside image_matching/tools/figures. The full set of data can be found in image_matching/HyDia_full_data.zip. The data present in image_matching/tools/figures are obtained using the full set of data. We have not included the full FRGC 2.0 RGB dataset (including the images), as it was provided by the CVRL lab at the University of Notre Dame and may contain private or proprietary content that cannot be publicly shared. Therefore, we record our result based on the obtained data (embeddings) and provide the code to generate graphs based on them, as they are the exact ones we present in the paper.



## Notes on Reusability (Only for Functional and Reproduced badges)
