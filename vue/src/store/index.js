import {createStore} from "vuex"
import axiosClient  from "../axios";

const store = createStore({
  state:{
    user:{
      data:{},
      token: sessionStorage.getItem('TOKEN'),
    }
  },
  getters: {},

  // Called using store.dispatch('function Name', payload)
  actions: {
    register({commit}, user){
      return axiosClient.post('/register', user)
      .then(({data})=>{
          commit('setUser', data);
          return data;
      })
    },
    login({commit}, user){
      return axiosClient.post('/login', user)
        .then(({data})=>{
            commit('setUser', data);
            return data;
        })
    },
    logout({commit}){
      return axiosClient.post('/logout')
        .then((resp)=>{
            commit('logout');
            return resp;
        })
    }
  },

  // Called using store.commit('function Name')
  mutations:{
    logout: state => {
      state.user.data = {};
      state.user.token = null;
      sessionStorage.removeItem('TOKEN');
    },
    setUser: (state, userData)=>{
      state.user.token = userData.token;
      state.user.data = userData.user;
      sessionStorage.setItem('TOKEN', userData.token);
    }
  },
  modules: {}
});

export default store;
