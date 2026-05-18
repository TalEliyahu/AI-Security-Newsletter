import { buildHeuristicJudgeReport } from "./rubric.mjs";

export class JudgeModelClient {
  async judgeIssue() {
    throw new Error("JudgeModelClient.judgeIssue must be implemented by a concrete client.");
  }
}

export class HeuristicJudgeModelClient extends JudgeModelClient {
  async judgeIssue(input) {
    return buildHeuristicJudgeReport(input);
  }
}

export class MockJudgeModelClient extends JudgeModelClient {
  constructor(response) {
    super();
    this.response = response;
  }

  async judgeIssue() {
    return this.response;
  }
}
