"""Fixture crew for spec 056: researcher reads files and a task sends email."""

from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai_tools import FileReadTool


@CrewBase
class VulnCrew:
    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def researcher(self) -> Agent:
        return Agent(config=self.agents_config["researcher"], tools=[FileReadTool()])

    @agent
    def reporter(self) -> Agent:
        return Agent(config=self.agents_config["reporter"])

    @task
    def research_task(self) -> Task:
        return Task(config=self.tasks_config["research_task"])

    @task
    def send_task(self) -> Task:
        return Task(config=self.tasks_config["send_task"])

    @task
    def report_task(self) -> Task:
        return Task(config=self.tasks_config["report_task"])

    @crew
    def crew(self) -> Crew:
        return Crew(agents=self.agents, tasks=self.tasks, process=Process.sequential)
