import gymnasium as gym
import math
import random
import numpy as np
from collections import namedtuple, deque
from itertools import count

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
import matplotlib
import matplotlib.pyplot as plt

BATCH_SIZE = 128
GAMMA = 0.999
EPS_START = 0.9
EPS_END = 0.05
EPS_DECAY = 200
TARGET_UPDATE = 10
LR = 1e-4
MEMORY_SIZE = 2000

env = gym.make("CartPole-v1")

# set up matplotlib
is_ipython = 'inline' in matplotlib.get_backend()
if is_ipython:
    from IPython import display

plt.ion()

# if GPU is to be used
device = torch.device(
    "cuda" if torch.cuda.is_available() else
    "mps" if torch.backends.mps.is_available() else
    "cpu"
)

# Define a simple replay memory class
Transition = namedtuple('Transition', ('state', 'action', 'next_state', 'reward'))

class ReplayMemory:
    def __init__(self, capacity):
        self.memory = deque([], maxlen=capacity)

    def push(self, *args):
        """Save a transition"""
        self.memory.append(Transition(*args))

    def sample(self, batch_size):
        return random.sample(self.memory, batch_size)

    def __len__(self):
        return len(self.memory)
    
class DQN(nn.Module):
    def __init__(self, state_size, action_size):
        super(DQN, self).__init__()
        self.fc1 = nn.Linear(state_size, 24)
        self.fc2 = nn.Linear(24, 24)
        self.fc3 = nn.Linear(24, action_size)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.fc3(x)
    
state_size = 4  # Adjust according to your state size
action_size = 2  # Adjust according to your action space
main_q_network = DQN(state_size, action_size)
target_q_network = DQN(state_size, action_size)
target_q_network.load_state_dict(main_q_network.state_dict())
optimizer = optim.AdamW(main_q_network.parameters(), lr=LR)

# Initialize replay memory
replay_memory = ReplayMemory(MEMORY_SIZE)
steps_done = 0

# Epsilon-greedy action selection
def select_action(state):
    global steps_done
    sample = random.random()
    eps_threshold = EPS_END + (EPS_START - EPS_END) * \
        math.exp(-1. * steps_done / EPS_DECAY)
    steps_done += 1
    if sample > eps_threshold:
        with torch.no_grad():
            return torch.argmax(main_q_network(torch.FloatTensor(state))).item()  # Exploit
    else:
        return torch.tensor([[random.choice(range(action_size))]], device=device, dtype=torch.long)  # Explore

episode_durations = []

# Training loop with reward tracking and plotting
def plot_durations(show_result=False):
    plt.figure(1)
    durations_t = torch.tensor(episode_durations, dtype=torch.float)
    if show_result:
        plt.title('Result')
    else:
        plt.clf()
        plt.title('Training...')
    plt.xlabel('Episode')
    plt.ylabel('Duration')
    plt.plot(durations_t.numpy())
    
    # Take 100 episode averages and plot them too
    if len(durations_t) >= 100:
        means = durations_t.unfold(0, 100, 1).mean(1).view(-1)
        means = torch.cat((torch.zeros(99), means))
        plt.plot(means.numpy())
    
    plt.pause(0.001)  # pause a bit so that plots are updated
    if is_ipython:
        if not show_result:
            display.display(plt.gcf())
            display.clear_output(wait=True)
        else:
            display.display(plt.gcf())

def optimize_model():
    if len(replay_memory) < BATCH_SIZE:
        return
    transitions = replay_memory.sample(BATCH_SIZE)
    batch = Transition(*zip(*transitions))

    # Mask for non-terminal states
    non_final_mask = torch.tensor(tuple(map(lambda s: s is not None, batch.next_state)), device=device, dtype=torch.bool)
    non_final_next_states = torch.cat([s for s in batch.next_state if s is not None])
    
    state_batch = torch.cat(batch.state)
    action_batch = torch.cat(batch.action)
    reward_batch = torch.cat(batch.reward)

    # Compute Q(s, a)
    state_action_values = main_q_network(state_batch).gather(1, action_batch)

    # Compute the target Q values (for non-terminal states)
    next_state_values = torch.zeros(BATCH_SIZE, device=device)
    with torch.no_grad():
        next_state_values[non_final_mask] = target_q_network(non_final_next_states).max(1)[0].detach()

    # Compute the expected Q values
    expected_state_action_values = (next_state_values * GAMMA) + reward_batch

    # Compute Huber loss
    criterion = nn.SmoothL1Loss()
    loss = criterion(state_action_values, expected_state_action_values.unsqueeze(1))

    # Optimize the model
    optimizer.zero_grad()
    loss.backward()
    # In-place gradient clipping
    torch.nn.utils.clip_grad_value_(main_q_network.parameters(), 100)
    optimizer.step()

def init_shard_space(num_shards=5, initial_load=10):
    """
    Initialize the shard space for the DQNSB TPS throughput optimization algorithm.
    
    Args:
        num_shards (int): Number of shards to initialize.
        initial_load (int): Initial load assigned to each shard.
        
    Returns:
        np.array: Initial state space representing shard loads.
    """
    shard_loads = np.full(num_shards, initial_load)
    
    
    return shard_loads

def execute_action(state, action):
    """
    Execute an action in the shard space and return the next state and reward.
    
    Args:
        state (np.array): Current state representing shard loads.
        action (int): Action to be executed, which affects the shard loads.
        
    Returns:
        tuple: Next state (np.array) and reward (float).
    """
    num_shards = len(state)
    
    shard_index = action // 2  # Determine which shard to modify
    direction = 1 if action % 2 == 0 else -1  # Increase or decrease
    
    state[shard_index] += direction
    
    state = np.clip(state, 0, None)  # Assuming load can't be negative
    
    reward = -np.sum(state**2) 
    
    return state, reward
# Run the DQN training loop
if torch.cuda.is_available() or torch.backends.mps.is_available():
    num_episodes = 600
else:
    num_episodes = 50

# Training Loop
rewards_per_episode = []
losses = []
q_values = []

for epoch in range(num_episodes):
    state, info = env.reset()  # Reset environment (init state space)
    state = torch.tensor([state], device=device, dtype=torch.float32)
    total_reward = 0
    
    for t in count():
        action = select_action(state)
        observation, reward, terminated, truncated, _ = env.step(action.item())
        reward = torch.tensor([reward], device=device)
        done = terminated or truncated

        if terminated:
            next_state = None
        else:
            next_state = torch.tensor(observation, dtype=torch.float32, device=device).unsqueeze(0)

        next_state, reward = execute_action(state, action)  # Implement this based on your environment
        total_reward += reward

        replay_memory.push(state, action, next_state, reward)
        state = next_state

        # Optimize the model
        optimize_model()
        target_net_state_dict = target_net.state_dict()
        policy_net_state_dict = policy_net.state_dict()
        # Update target network at regular intervals
        if epoch % TARGET_UPDATE == 0:
            target_net.load_state_dict(policy_net.state_dict())

        if done:
            episode_durations.append(t + 1)
            plot_durations()
            break
    rewards_per_episode.append(total_reward)
    if epoch % 10 == 0: 
        target_q_network.load_state_dict(main_q_network.state_dict())

    with torch.no_grad():
        q_values.append(torch.max(main_q_network(torch.FloatTensor(state))).item())
    

print('Complete')
plot_durations(show_result=True)
plt.ioff()
plt.show()