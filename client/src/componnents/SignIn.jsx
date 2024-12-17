import React, { useState } from "react";
import styled from "styled-components";
import TextInput from "./TextInput";
import Button from "./Button";
import { UserSignIn } from "../api";
import { useDispatch } from "react-redux";
import { loginSuccess } from "../redux/reducers/userSlice";
import { openSnackbar } from "../redux/reducers/snackbarSlice";

const Container = styled.div`
  width: 100%;
  max-width: 500px;
  display: flex;
  flex-direction: column;
  gap: 36px;
`;

const Title = styled.div`
  font-size: 30px;
  font-weight: 800;
  color: ${({ theme }) => theme.secondary};
`;
const Span = styled.div`
  font-size: 16px;
  font-weight: 400;
  color: ${({ theme }) => theme.secondary + 90};
`;
const TextButton = styled.div`
  width: 100%;
  text-align: end;
  color: ${({ theme }) => theme.secondary + 90};
  cursor: pointer;
  font-size: 14px;
  transition: all 0.3s ease;
  font-weight: 500;
  &:hover {
    color: ${({ theme }) => theme.primary};
  }
`;

const SignIn = ({ setOpenAuth }) => {
  return <Container>
    <div>
      <Title>
        Welcome to Airbnb
      </Title>
      <Span>Please login with your details here</Span>
    </div>
    <div style={{display:"flex",gap:"20px", flexDirection:"column"}}>
      <TextInput label="Email" placeholder="Enter your email"/>
      <TextInput label="Password" placeholder="Enter your password" password/>
      <TextButton>Forget Password?</TextButton>
      <Button text="Sign In"/>
    </div>
  </Container>;
};

export default SignIn;
