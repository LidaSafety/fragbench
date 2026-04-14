export const store = {
  state: {
    activeView: "campaigns",
    runs: [],
    data: null,
  },
  set(partial) {
    this.state = { ...this.state, ...partial };
  },
};
